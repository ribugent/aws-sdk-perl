# Generated by default/object.tt
package Paws::Comprehend::AugmentedManifestsListItem;
  use Moose;
  has AttributeNames => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);
  has S3Uri => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Comprehend::AugmentedManifestsListItem

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Comprehend::AugmentedManifestsListItem object:

  $service_obj->Method(Att1 => { AttributeNames => $value, ..., S3Uri => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Comprehend::AugmentedManifestsListItem object:

  $result = $service_obj->Method(...);
  $result->Att1->AttributeNames

=head1 DESCRIPTION

An augmented manifest file that provides training data for your custom
model. An augmented manifest file is a labeled dataset that is produced
by Amazon SageMaker Ground Truth.

=head1 ATTRIBUTES


=head2 B<REQUIRED> AttributeNames => ArrayRef[Str|Undef]

The JSON attribute that contains the annotations for your training
documents. The number of attribute names that you specify depends on
whether your augmented manifest file is the output of a single labeling
job or a chained labeling job.

If your file is the output of a single labeling job, specify the
LabelAttributeName key that was used when the job was created in Ground
Truth.

If your file is the output of a chained labeling job, specify the
LabelAttributeName key for one or more jobs in the chain. Each
LabelAttributeName key provides the annotations from an individual job.


=head2 B<REQUIRED> S3Uri => Str

The Amazon S3 location of the augmented manifest file.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Comprehend>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

