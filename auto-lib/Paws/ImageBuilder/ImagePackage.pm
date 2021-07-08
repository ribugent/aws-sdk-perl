# Generated by default/object.tt
package Paws::ImageBuilder::ImagePackage;
  use Moose;
  has PackageName => (is => 'ro', isa => 'Str', request_name => 'packageName', traits => ['NameInRequest']);
  has PackageVersion => (is => 'ro', isa => 'Str', request_name => 'packageVersion', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ImageBuilder::ImagePackage

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ImageBuilder::ImagePackage object:

  $service_obj->Method(Att1 => { PackageName => $value, ..., PackageVersion => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ImageBuilder::ImagePackage object:

  $result = $service_obj->Method(...);
  $result->Att1->PackageName

=head1 DESCRIPTION

Represents a package installed on an Image Builder image.

=head1 ATTRIBUTES


=head2 PackageName => Str

The name of the package as reported to the operating system package
manager.


=head2 PackageVersion => Str

The version of the package as reported to the operating system package
manager.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ImageBuilder>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

