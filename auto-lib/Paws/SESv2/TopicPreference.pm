# Generated by default/object.tt
package Paws::SESv2::TopicPreference;
  use Moose;
  has SubscriptionStatus => (is => 'ro', isa => 'Str', required => 1);
  has TopicName => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SESv2::TopicPreference

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SESv2::TopicPreference object:

  $service_obj->Method(Att1 => { SubscriptionStatus => $value, ..., TopicName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SESv2::TopicPreference object:

  $result = $service_obj->Method(...);
  $result->Att1->SubscriptionStatus

=head1 DESCRIPTION

The contact's preference for being opted-in to or opted-out of a topic.

=head1 ATTRIBUTES


=head2 B<REQUIRED> SubscriptionStatus => Str

The contact's subscription status to a topic which is either C<OPT_IN>
or C<OPT_OUT>.


=head2 B<REQUIRED> TopicName => Str

The name of the topic.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SESv2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

